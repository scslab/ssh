{-# LANGUAGE FlexibleInstances, TypeSynonymInstances #-}
module SSH.Session where

import Control.Concurrent.Chan
import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Data.Binary (decode, encode)
import Data.Word
import System.IO
import qualified Codec.Crypto.SimpleAES as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as M

import SSH.Channel
import SSH.Crypto
import SSH.Debug
import SSH.NetReader
import SSH.Packet
import SSH.Sender
import SSH.Util


type Session = StateT SessionState IO

data SessionState
    = Initial
        { ssConfig :: SessionConfig
        , ssChannelConfig :: ChannelConfig
        , ssThem :: Handle
        , ssSend :: SenderMessage -> IO ()
        , ssPayload :: LBS.ByteString
        , ssTheirVersion :: String
        , ssOurKEXInit :: LBS.ByteString
        , ssInSeq :: Word32
        }
    | GotKEXInit
        { ssConfig :: SessionConfig
        , ssChannelConfig :: ChannelConfig
        , ssThem :: Handle
        , ssSend :: SenderMessage -> IO ()
        , ssPayload :: LBS.ByteString
        , ssTheirVersion :: String
        , ssOurKEXInit :: LBS.ByteString
        , ssInSeq :: Word32
        , ssTheirKEXInit :: LBS.ByteString
        , ssOutCipher :: Cipher
        , ssInCipher :: Cipher
        , ssOutHMACPrep :: LBS.ByteString -> HMAC
        , ssInHMACPrep :: LBS.ByteString -> HMAC
        }
    | Final
        { ssConfig :: SessionConfig
        , ssChannelConfig :: ChannelConfig
        , ssChannels :: M.Map Word32 (Chan ChannelMessage)
        , ssID :: LBS.ByteString
        , ssThem :: Handle
        , ssSend :: SenderMessage -> IO ()
        , ssPayload :: LBS.ByteString
        , ssGotNEWKEYS :: Bool
        , ssInSeq :: Word32
        , ssInCipher :: Cipher
        , ssInHMAC :: HMAC
        , ssInKey :: BS.ByteString
        , ssInVector :: BS.ByteString
        , ssUser :: Maybe String
        }

data SessionConfig =
    SessionConfig
        { scAuthMethods :: [String]
        , scAuthorize :: Authorize -> Session Bool
        , scKeyPair :: KeyPair
        }

data Authorize
    = Password String String
    | PublicKey String PublicKey

instance Sender Session where
    send m = gets ssSend >>= io . ($ m)


defaultSessionConfig :: SessionConfig
defaultSessionConfig =
    SessionConfig
        { scAuthMethods = ["publickey"]
        , scAuthorize = const (return True)
        , scKeyPair = RSAKeyPair (RSAPublicKey 0 0) 0
        {-\(Password u p) ->-}
            {-return $ u == "test" && p == "test"-}
        }

net :: NetReader a -> Session a
net r = do
    pl <- gets ssPayload

    let (res, new) = runState r pl

    modify (\s -> s { ssPayload = new })
    return res

newChannelID :: Session Word32
newChannelID = gets ssChannels >>= return . findNext . M.keys
  where
    findNext :: [Word32] -> Word32
    findNext ks = head . filter (not . (`elem` ks)) $ [0..]

getChannel :: Word32 -> Session (Chan ChannelMessage)
getChannel i = do
    mc <- gets (M.lookup i . ssChannels)
    case mc of
        Just c -> return c
        Nothing -> error $ "unknown channel: " ++ show i

decrypt :: LBS.ByteString -> Session LBS.ByteString
decrypt m
    | m == LBS.empty = return m
    | otherwise = do
    s <- get
    case s of
        Final
            { ssInCipher = Cipher AES CBC bs@16 _
            , ssInKey = key
            , ssInVector = vector
            } -> do
                let blocks = toBlocks bs m
                    decrypted =
                      A.crypt A.CBC key vector A.Decrypt m

                modify (\ss -> ss { ssInVector = strictLBS $ last blocks })
                return decrypted
        _ -> error "no decrypt for current state"

getPacket :: Session ()
getPacket = do
    s <- get
    h <- gets ssThem
    case s of
        Final
            { ssGotNEWKEYS = True
            , ssInCipher = Cipher _ _ bs _
            , ssInHMAC = HMAC ms f
            , ssInSeq = is
            } -> do
                let firstChunk = max 8 bs

                firstEnc <- liftIO $ LBS.hGet h firstChunk
                first <- decrypt firstEnc

                let packetLen = decode (LBS.take 4 first) :: Word32
                    paddingLen = decode (LBS.drop 4 first) :: Word8

                dump ("got packet", is, first, packetLen, paddingLen)

                restEnc <- liftIO $ LBS.hGet h (fromIntegral packetLen - firstChunk + 4)

                dump ("got rest", restEnc)

                rest <- decrypt restEnc

                dump ("decrypted", rest)
                let decrypted = first `LBS.append` rest
                    payload = extract packetLen paddingLen decrypted

                dump ("getting hmac", ms)

                mac <- liftIO $ LBS.hGet h ms

                dump ("got mac", mac, decrypted, is)
                dump ("hmac'd", f decrypted)
                dump ("got mac, valid?", verify mac is decrypted f)

                modify (\ss -> ss { ssPayload = payload })
        _ -> do
            first <- liftIO $ LBS.hGet h 5

            let packetLen = decode (LBS.take 4 first) :: Word32
                paddingLen = decode (LBS.drop 4 first) :: Word8

            rest <- liftIO $ LBS.hGet h (fromIntegral packetLen - 5 + 4)
            let payload = LBS.take (fromIntegral packetLen - fromIntegral paddingLen - 1) rest
            modify (\ss -> ss { ssPayload = payload })
  where
    extract pkl pdl d = LBS.take (fromIntegral pkl - fromIntegral pdl - 1) (LBS.drop 5 d)
    verify m is d f = m == f (encode (fromIntegral is :: Word32) `LBS.append` d)
