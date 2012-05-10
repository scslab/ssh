module SSH.Sender where

import Control.Concurrent.Chan
import Control.Monad (replicateM)
import Data.Word
import System.IO
import System.Random
import qualified Codec.Crypto.SimpleAES as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import SSH.Debug
import SSH.Crypto
import SSH.Packet
import SSH.Util


data SenderState
    = NoKeys
        { senderThem :: Handle
        , senderOutSeq :: Word32
        }
    | GotKeys
        { senderThem :: Handle
        , senderOutSeq :: Word32
        , senderEncrypting :: Bool
        , senderCipher :: Cipher
        , senderKey :: BS.ByteString
        , senderVector :: BS.ByteString
        , senderHMAC :: HMAC
        }

data SenderMessage
    = Prepare Cipher BS.ByteString BS.ByteString HMAC
    | StartEncrypting
    | Send LBS.ByteString
    | Stop

class Sender a where
    send :: SenderMessage -> a ()

    sendPacket :: Packet () -> a ()
    sendPacket = send . Send . doPacket

sender :: Chan SenderMessage -> SenderState -> IO ()
sender ms ss = do
    m <- readChan ms
    case m of
        Stop -> return ()
        Prepare cipher key iv hmac -> do
            dump ("initiating encryption", key, iv)
            sender ms (GotKeys (senderThem ss) (senderOutSeq ss) False cipher key iv hmac)
        StartEncrypting -> do
            dump ("starting encryption")
            sender ms (ss { senderEncrypting = True })
        Send msg -> do
            pad <- fmap (LBS.pack . map fromIntegral) $
                replicateM (fromIntegral $ paddingLen msg) (randomRIO (0, 255 :: Int))

            let f = full msg pad

            case ss of
                GotKeys h os True cipher key iv (HMAC _ mac) -> do
                    dump ("sending encrypted", os, f)
                    let (encrypted, newVector) = encrypt cipher key iv f
                    LBS.hPut h . LBS.concat $
                        [ encrypted
                        , mac . doPacket $ long os >> raw f
                        ]
                    hFlush h
                    sender ms $ ss
                        { senderOutSeq = senderOutSeq ss + 1
                        , senderVector = newVector
                        }
                _ -> do
                    dump ("sending unencrypted", senderOutSeq ss, f)
                    LBS.hPut (senderThem ss) f
                    hFlush (senderThem ss)
                    sender ms (ss { senderOutSeq = senderOutSeq ss + 1 })
  where
    blockSize =
        case ss of
            GotKeys { senderCipher = Cipher _ _ bs _ }
                | bs > 8 -> bs
            _ -> 8

    full msg pad = doPacket $ do
        long (len msg)
        byte (paddingLen msg)
        raw msg
        raw pad

    len :: LBS.ByteString -> Word32
    len msg = 1 + fromIntegral (LBS.length msg) + fromIntegral (paddingLen msg)

    paddingNeeded :: LBS.ByteString -> Word8
    paddingNeeded msg = fromIntegral blockSize - (fromIntegral $ (5 + LBS.length msg) `mod` fromIntegral blockSize)

    paddingLen :: LBS.ByteString -> Word8
    paddingLen msg =
        if paddingNeeded msg < 4
            then paddingNeeded msg + fromIntegral blockSize
            else paddingNeeded msg

encrypt :: Cipher -> BS.ByteString -> BS.ByteString -> LBS.ByteString -> (LBS.ByteString, BS.ByteString)
encrypt (Cipher AES CBC bs _) key vector m =
    ( fromBlocks encrypted
    , case encrypted of
          (_:_) -> strictLBS (last encrypted)
          [] -> error ("encrypted data empty for `" ++ show m ++ "' in encrypt") vector
    )
  where
    encrypted = toBlocks bs $ A.crypt A.CBC key vector A.Encrypt m
