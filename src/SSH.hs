module SSH where

import Control.Concurrent (forkIO)
import Control.Concurrent.Chan
import Control.Monad (replicateM, when)
import Control.Monad.Trans.State
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Crypto.HMAC
import Crypto.Hash.MD5
import Crypto.Hash.SHA1
import Data.List (intercalate)
import Data.List.Split (splitOn)
import Network
import OpenSSL.BN (randIntegerOneToNMinusOne)
import System.IO
import System.Random
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as M
import qualified Data.Serialize as S

import SSH.Channel
import SSH.Crypto
import SSH.Debug
import SSH.NetReader
import SSH.Packet
import SSH.Sender
import SSH.Session
import SSH.Util


version :: String
version = "SSH-2.0-DarcsDen"

supportedKeyExchanges :: [String]
supportedKeyExchanges =
    {-"diffie-hellman-group-exchange-sha1," ++-}
    ["diffie-hellman-group1-sha1"]

supportedKeyAlgorithms :: [String]
supportedKeyAlgorithms = ["ssh-rsa", "ssh-dss"]

supportedCiphers :: [(String, Cipher)]
supportedCiphers =
    [ ("aes256-cbc", aesCipher CBC 32)
    , ("aes192-cbc", aesCipher CBC 24)
    , ("aes128-cbc", aesCipher CBC 16)
    ]
  where
    aesCipher m s =
        Cipher AES m 16 s

supportedMACs :: [(String, LBS.ByteString -> HMAC)]
supportedMACs =
    [ ("hmac-sha1", makeHMAC True)
    , ("hmac-md5", makeHMAC False)
    ]
  where
    makeHMAC True k = HMAC 20 $ \b -> bsToLBS . S.runPut $ S.put (hmac (MacKey (strictLBS (LBS.take 20 k))) b :: SHA1)
    makeHMAC False k = HMAC 16 $ \b -> bsToLBS . S.runPut $ S.put (hmac (MacKey (strictLBS (LBS.take 16 k))) b :: MD5)

    bsToLBS = LBS.fromChunks . (: [])

supportedCompression :: String
supportedCompression = "none"

supportedLanguages :: String
supportedLanguages = ""

start :: SessionConfig -> ChannelConfig -> PortNumber -> IO ()
start sc cc p = withSocketsDo $ do
    sock <- listenOn (PortNumber p)
    putStrLn $ "ssh server listening on port " ++ show p
    waitLoop sc cc sock

waitLoop :: SessionConfig -> ChannelConfig -> Socket -> IO ()
waitLoop sc cc s = do
    (handle, hostName, port) <- accept s

    io $ hSetBinaryMode handle True

    dump ("got connection from", hostName, port)

    forkIO $ do
        -- send SSH server version
        hPutStr handle (version ++ "\r\n")
        hFlush handle

        done <- hIsEOF handle
        if done
            then return ()
            else do

        -- get the version response
        theirVersion <- hGetLine handle >>= return . takeWhile (/= '\r')

        cookie <- fmap (LBS.pack . map fromIntegral) $
            replicateM 16 (randomRIO (0, 255 :: Int))

        let ourKEXInit = doPacket $ pKEXInit cookie

        out <- newChan
        forkIO (sender out (NoKeys handle 0))

        evalStateT
            (send (Send ourKEXInit) >> readLoop)
            (Initial
                { ssConfig = sc
                , ssChannelConfig = cc
                , ssThem = handle
                , ssSend = writeChan out
                , ssPayload = LBS.empty
                , ssTheirVersion = theirVersion
                , ssOurKEXInit = ourKEXInit
                , ssInSeq = 0
                })

    waitLoop sc cc s
  where
    pKEXInit :: LBS.ByteString -> Packet ()
    pKEXInit cookie = do
        byte 20

        raw cookie

        mapM_ string
            [ intercalate "," $ supportedKeyExchanges
            , intercalate "," $ supportedKeyAlgorithms
            , intercalate "," $ map fst supportedCiphers
            , intercalate "," $ map fst supportedCiphers
            , intercalate "," $ map fst supportedMACs
            , intercalate "," $ map fst supportedMACs
            , supportedCompression
            , supportedCompression
            , supportedLanguages
            , supportedLanguages
            ]

        byte 0 -- first_kex_packet_follows (boolean)
        long 0

readLoop :: Session ()
readLoop = do
    done <- gets ssThem >>= io . hIsEOF
    if done
        then shutdownChannels
        else do

    getPacket

    msg <- net readByte

    if msg == 1 || msg == 97 -- disconnect || close
        then shutdownChannels
        else do

    case msg of
        5 -> serviceRequest
        20 -> kexInit
        21 -> newKeys
        30 -> kexDHInit
        50 -> userAuthRequest
        90 -> channelOpen
        94 -> dataReceived
        96 -> eofReceived
        98 -> channelRequest
        u -> dump $ "unknown message: " ++ show u

    modify (\s -> s { ssInSeq = ssInSeq s + 1 })
    readLoop
  where
    shutdownChannels = do
        s <- get
        case s of
            Final { ssChannels = cs } ->
                mapM_ (io . flip writeChan Interrupt) (M.elems cs)
            _ -> return ()

        io $ ssSend s Stop

kexInit :: Session ()
kexInit = do
    cookie <- net (readBytes 16)
    nameLists <- fmap (map (splitOn "," . fromLBS)) (replicateM 10 (net readLBS))
    kpf <- net readByte
    dummy <- net readULong

    let theirKEXInit = reconstruct cookie nameLists kpf dummy
        ocn = match (nameLists !! 3) (map fst supportedCiphers)
        icn = match (nameLists !! 2) (map fst supportedCiphers)
        omn = match (nameLists !! 5) (map fst supportedMACs)
        imn = match (nameLists !! 4) (map fst supportedMACs)

    dump ("KEXINIT", theirKEXInit, ocn, icn, omn, imn)
    modify $ \st ->
        case st of
            Initial c cc h s p cv sk is ->
                case
                    ( lookup ocn supportedCiphers
                    , lookup icn supportedCiphers
                    , lookup omn supportedMACs
                    , lookup imn supportedMACs
                    ) of
                    (Just oc, Just ic, Just om, Just im) ->
                        GotKEXInit
                            { ssConfig = c
                            , ssChannelConfig = cc
                            , ssThem = h
                            , ssSend = s
                            , ssPayload = p
                            , ssTheirVersion = cv
                            , ssOurKEXInit = sk
                            , ssTheirKEXInit = theirKEXInit
                            , ssOutCipher = oc
                            , ssInCipher = ic
                            , ssOutHMACPrep = om
                            , ssInHMACPrep = im
                            , ssInSeq = is
                            }
                    _ ->
                        error . concat $
                            [ "impossible: lookup failed for ciphers/macs: "
                            , show (ocn, icn, omn, imn)
                            ]
            _ -> error "impossible state transition; expected Initial"
  where
    match n h = head . filter (`elem` h) $ n
    reconstruct c nls kpf dummy = doPacket $ do
        byte 20
        raw c
        mapM_ (string . intercalate ",") nls
        byte kpf
        long dummy

kexDHInit :: Session ()
kexDHInit = do
    e <- net readInteger
    dump ("KEXDH_INIT", e)

    y <- io $ randIntegerOneToNMinusOne ((safePrime - 1) `div` 2) -- q?

    let f = modexp generator y safePrime
        k = modexp e y safePrime

    keyPair <- gets (scKeyPair . ssConfig)

    let pub =
            case keyPair of
                RSAKeyPair { rprivPub = p } -> p
                DSAKeyPair { dprivPub = p } -> p
    d <- digest e f k pub

    let [civ, siv, ckey, skey, cinteg, sinteg] = map (makeKey k d) ['A'..'F']
    dump ("DECRYPT KEY/IV", LBS.take 16 ckey, LBS.take 16 civ)

    oc <- gets ssOutCipher
    om <- gets ssOutHMACPrep
    send $
        Prepare
            oc
            (strictLBS $ LBS.take (fromIntegral $ cKeySize oc) $ skey)
            (strictLBS $ LBS.take (fromIntegral $ cBlockSize oc) $ siv)
            (om sinteg)

    modify $ \st ->
        case st of
            GotKEXInit c cc h s p _ _ is _ _ ic _ im ->
                Final
                    { ssConfig = c
                    , ssChannelConfig = cc
                    , ssChannels = M.empty
                    , ssID = d
                    , ssThem = h
                    , ssSend = s
                    , ssPayload = p
                    , ssGotNEWKEYS = False
                    , ssInSeq = is
                    , ssInCipher = ic
                    , ssInHMAC = im cinteg
                    , ssInKey =
                        strictLBS $ LBS.take (fromIntegral $ cKeySize ic) $ ckey
                    , ssInVector =
                        strictLBS $ LBS.take (fromIntegral $ cBlockSize ic) $ civ
                    , ssUser = Nothing
                    }

            _ -> error "impossible state transition; expected GotKEXInit"



    signed <- io $ sign keyPair d
    let reply = doPacket (kexDHReply f signed pub)
    dump ("KEXDH_REPLY", reply)

    send (Send reply)
  where
    kexDHReply f s p = do
        byte 31
        byteString (blob p)
        integer f
        byteString s

    digest e f k p = do
        cv <- gets ssTheirVersion
        ck <- gets ssTheirKEXInit
        sk <- gets ssOurKEXInit
        return . bytestringDigest . sha1 . doPacket $ do
            string cv
            string version
            byteString ck
            byteString sk
            byteString (blob p)
            integer e
            integer f
            integer k

newKeys :: Session ()
newKeys = do
    sendPacket (byte 21)
    send StartEncrypting
    modify (\ss -> ss { ssGotNEWKEYS = True })

serviceRequest :: Session ()
serviceRequest = do
    name <- net readLBS
    sendPacket $ do
        byte 6
        byteString name

userAuthRequest :: Session ()
userAuthRequest = do
    user <- net readLBS
    service <- net readLBS
    method <- net readLBS

    auth <- gets (scAuthorize . ssConfig)
    authMethods <- gets (scAuthMethods . ssConfig)

    dump ("userauth attempt", user, service, method)
    check <- case fromLBS method of
        x | not (x `elem` authMethods) ->
            return False

        "publickey" -> do
            b <- net readByte
            name <- net readLBS
            key <- net readLBS
            ch <- auth (PublicKey (fromLBS user) (blobToKey key))

            -- if it's signed, assume it's the second one after auth
            if ch && b == 1
                then sendPacket userAuthOK
                else when ch (sendPacket $ userAuthPKOK name key)

            return ch

        "password" -> do
            0 <- net readByte
            password <- net readLBS
            ch <- auth (Password (fromLBS user) (fromLBS password))
            when ch (sendPacket userAuthOK)
            return ch

        u -> error $ "unhandled authorization type: " ++ u

    if check
        then modify (\s -> s { ssUser = Just (fromLBS user) })
        else sendPacket (userAuthFail authMethods)
  where
    userAuthFail ms = do
        byte 51
        string (intercalate "," ms)
        byte 0

    userAuthPKOK name key = do
        byte 60
        byteString name
        byteString key

    userAuthOK = byte 52

channelOpen :: Session ()
channelOpen = do
    name <- net readLBS
    them <- net readULong
    windowSize <- net readULong
    maxPacketLength <- net readULong

    dump ("channel open", name, them, windowSize, maxPacketLength)

    us <- newChannelID

    chan <- do
        c <- gets ssChannelConfig
        s <- gets ssSend
        Just u <- gets ssUser
        io $ newChannel c s us them windowSize maxPacketLength u

    modify (\s -> s
        { ssChannels = M.insert us chan (ssChannels s) })

channelRequest :: Session ()
channelRequest = do
    chan <- net readULong >>= getChannel
    typ <- net readLBS
    wantReply <- net readBool

    let sendRequest = io . writeChan chan . Request wantReply

    case fromLBS typ of
        "pty-req" -> do
            term <- net readString
            cols <- net readULong
            rows <- net readULong
            width <- net readULong
            height <- net readULong
            modes <- net readString
            sendRequest (PseudoTerminal term cols rows width height modes)

        "x11-req" -> sendRequest X11Forwarding

        "shell" -> sendRequest Shell

        "exec" -> do
            command <- net readString
            dump ("execute command", command)
            sendRequest (Execute command)

        "subsystem" -> do
            name <- net readString
            dump ("subsystem request", name)
            sendRequest (Subsystem name)

        "env" -> do
            name <- net readString
            value <- net readString
            dump ("environment request", name, value)
            sendRequest (Environment name value)

        "window-change" -> do
            cols <- net readULong
            rows <- net readULong
            width <- net readULong
            height <- net readULong
            sendRequest (WindowChange cols rows width height)

        "xon-xoff" -> do
            b <- net readBool
            sendRequest (FlowControl b)

        "signal" -> do
            name <- net readString
            sendRequest (Signal name)

        "exit-status" -> do
            status <- net readULong
            sendRequest (ExitStatus status)

        "exit-signal" -> do
            name <- net readString
            dumped <- net readBool
            msg <- net readString
            lang <- net readString
            sendRequest (ExitSignal name dumped msg lang)

        u -> sendRequest (Unknown u)

    dump ("request processed")

dataReceived :: Session ()
dataReceived = do
    dump "got data"
    chan <- net readULong >>= getChannel
    msg <- net readLBS
    io $ writeChan chan (Data msg)
    dump "data processed"


eofReceived :: Session ()
eofReceived = do
    chan <- net readULong >>= getChannel
    io $ writeChan chan EOF
