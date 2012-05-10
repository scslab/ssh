{-# LANGUAGE FlexibleInstances, TypeSynonymInstances #-}
module SSH.Channel where

import Control.Concurrent
import Control.Monad (when)
import Control.Monad.Trans.State
import Data.Word
import System.Exit
import System.IO
import System.Process
import qualified Data.ByteString.Lazy as LBS

import SSH.Debug
import SSH.Packet
import SSH.Sender

type Channel = StateT ChannelState IO

data ChannelState =
    ChannelState
        { csConfig :: ChannelConfig
        , csID :: Word32
        , csTheirID :: Word32
        , csSend :: SenderMessage -> IO ()
        , csDataReceived :: Word32
        , csMaxPacket :: Word32
        , csWindowSize :: Word32
        , csTheirWindowSize :: Word32
        , csUser :: String
        , csProcess :: Maybe Process
        , csRedirector :: Maybe ThreadId
        }

data ChannelMessage
    = Request Bool ChannelRequest
    | Data LBS.ByteString
    | EOF
    | Interrupt
    deriving Show

data ChannelConfig =
    ChannelConfig
        { ccRequestHandler :: Bool -> ChannelRequest -> Channel ()
        }

data ChannelRequest
    = Shell
    | Execute String
    | Subsystem String
    | X11Forwarding
    | Environment String String
    | PseudoTerminal String Word32 Word32 Word32 Word32 String
    | WindowChange Word32 Word32 Word32 Word32
    | Signal String
    | ExitStatus Word32
    | ExitSignal String Bool String String
    | FlowControl Bool
    | Unknown String
    deriving Show

data Process =
    Process
        { pHandle :: ProcessHandle
        , pIn :: Handle
        , pOut :: Handle
        , pError :: Handle
        }

instance Sender Channel where
    send m = gets csSend >>= io . ($ m)


defaultChannelConfig :: ChannelConfig
defaultChannelConfig =
    ChannelConfig
        { ccRequestHandler = \wr req ->
            case req of
                Execute cmd -> do
                    spawnProcess (runInteractiveCommand cmd)
                    when wr channelSuccess
                _ -> do
                    channelError "accepting 'exec' requests only"
                    when wr channelFail
        }

newChannel :: ChannelConfig -> (SenderMessage -> IO ()) -> Word32 -> Word32 -> Word32 -> Word32 -> String -> IO (Chan ChannelMessage)
newChannel config csend us them winSize maxPacket user = do
    chan <- newChan

    dump ("new channel", winSize, maxPacket)
    forkIO $ evalStateT (do
        sendPacket $ do
            byte 91
            long them
            long us
            long (32768 * 64)
            long 32768

        chanLoop chan) $
        ChannelState
            { csConfig = config
            , csID = us
            , csTheirID = them
            , csSend = csend
            , csDataReceived = 0
            , csMaxPacket = maxPacket
            , csWindowSize = 32768 * 64
            , csTheirWindowSize = winSize
            , csUser = user
            , csProcess = Nothing
            , csRedirector = Nothing
            }

    return chan

chanLoop :: Chan ChannelMessage -> Channel ()
chanLoop c = do
    msg <- io (readChan c)
    dump ("got channel message", msg)

    chanid <- gets csID
    case msg of
        Request wr cr -> do
            handler <- gets (ccRequestHandler . csConfig)
            handler wr cr

            chanLoop c

        Data datum -> do
            modify $ \cs -> cs
                { csDataReceived =
                    csDataReceived cs + fromIntegral (LBS.length datum)
                }

            -- Adjust window size if needed
            rcvd <- gets csDataReceived
            maxp <- gets csMaxPacket
            winSize <- gets csTheirWindowSize
            when (rcvd + (maxp * 4) >= winSize && winSize + (maxp * 4) <= 2^(32 :: Integer) - 1) $ do
                modify $ \cs -> cs { csTheirWindowSize = winSize + (maxp * 4) }
                sendPacket $ do
                    byte 93
                    long chanid
                    long (maxp * 4)

            -- Direct input to process's stdin
            cproc <- gets csProcess
            case cproc of
                Nothing -> dump ("got unhandled data", chanid)
                Just (Process _ pin _ _) -> do
                    dump ("redirecting data", chanid, LBS.length datum)
                    io $ LBS.hPut pin datum
                    io $ hFlush pin

            chanLoop c

        EOF -> do
            modify $ \cs -> cs { csDataReceived = 0 }

            -- Close process's stdin to indicate EOF
            cproc <- gets csProcess
            case cproc of
                Nothing -> dump ("got unhandled eof")
                Just (Process _ pin _ _) -> do
                    dump ("redirecting eof", chanid)
                    io $ hClose pin

            chanLoop c

        Interrupt -> do
            -- shut down the i/o redirecting process
            redir <- gets csRedirector
            case redir of
                Nothing -> return ()
                Just tid -> io (killThread tid)

            cproc <- gets csProcess
            case cproc of
                Nothing -> return ()
                Just (Process phdl _ _ _) -> do
                    -- NOTE: this doesn't necessarily guarantee termination
                    -- see System.Process docs
                    io $ terminateProcess phdl


channelError :: String -> Channel ()
channelError msg = do
    target <- gets csTheirID
    sendPacket $ do
        byte 95
        long target
        long 1
        string (msg ++ "\r\n")

channelMessage :: String -> Channel ()
channelMessage msg = do
    target <- gets csTheirID
    sendPacket $ do
        byte 94
        long target
        string (msg ++ "\r\n")

channelFail :: Channel ()
channelFail = do
    target <- gets csTheirID
    sendPacket $ do
        byte 100
        long target

channelSuccess :: Channel ()
channelSuccess = do
    target <- gets csTheirID
    sendPacket $ do
        byte 99
        long target

channelDone :: Channel ()
channelDone = do
    target <- gets csTheirID
    sendPacket (byte 96 >> long target) -- eof
    sendPacket (byte 97 >> long target) -- close

sendChunks :: Integral a => a -> Packet () -> String -> Channel ()
sendChunks _ _ "" = return ()
sendChunks n p s = do
    sendPacket (p >> string chunk)
    sendChunks n p rest
  where
    (chunk, rest) = splitAt (fromIntegral n - packetLength p) s

redirectHandle :: Chan () -> Packet () -> Handle -> Channel ()
redirectHandle f d h = do
    s <- get
    r <- io . forkIO . evalStateT redirectLoop $ s
    modify $ \cs -> cs { csRedirector = Just r }
  where
    redirectLoop = do
        maxLen <- gets csMaxPacket

        dump "reading..."
        l <- io $ getAvailable
        dump ("read data from handle", l)

        if not (null l)
            then sendChunks maxLen d l
            else return ()

        done <- io $ hIsEOF h
        dump ("eof handle?", done)
        if done
            then io $ writeChan f ()
            else redirectLoop

    getAvailable :: IO String
    getAvailable = do
        ready <- hReady h `catch` const (return False)
        if not ready
            then return ""
            else do
                c <- hGetChar h
                cs <- getAvailable
                return (c:cs)

spawnProcess :: IO (Handle, Handle, Handle, ProcessHandle) -> Channel ()
spawnProcess cmd = do
    target <- gets csTheirID

    (pin, pout, perr, phdl) <- io cmd
    modify (\s -> s { csProcess = Just $ Process phdl pin pout perr })

    dump ("command spawned")

    -- redirect stdout and stderr, using a channel to signal completion
    done <- io newChan
    io $ hSetBinaryMode pout True
    io $ hSetBinaryMode perr True
    redirectHandle done (byte 94 >> long target) pout
    redirectHandle done (byte 95 >> long target >> long 1) perr

    s <- get

    -- spawn a thread to wait for the process to terminate
    io . forkIO $ do
        -- wait until both are done
        readChan done
        readChan done

        dump "done reading output! waiting for process..."
        exit <- io $ waitForProcess phdl
        dump ("process exited", exit)

        flip evalStateT s $ do
            sendPacket $ do
                byte 98
                long target
                string "exit-status"
                byte 0
                long (statusCode exit)

            channelDone

    return ()
  where
    statusCode ExitSuccess = 0
    statusCode (ExitFailure n) = fromIntegral n

