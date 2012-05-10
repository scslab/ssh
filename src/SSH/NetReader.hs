module SSH.NetReader where

import Control.Monad.Trans.State
import Data.Binary (decode)
import Data.Int
import Data.Word
import qualified Data.ByteString.Lazy as LBS

import SSH.Packet
import SSH.Util (fromLBS)


type NetReader = State LBS.ByteString


readByte :: NetReader Word8
readByte = fmap LBS.head (readBytes 1)

readLong :: NetReader Int32
readLong = fmap decode (readBytes 4)

readULong :: NetReader Word32
readULong = fmap decode (readBytes 4)

readInteger :: NetReader Integer
readInteger = do
    len <- readULong
    b <- readBytes (fromIntegral len)
    return (unmpint b)

readBytes :: Int -> NetReader LBS.ByteString
readBytes n = do
    p <- gets (LBS.take (fromIntegral n))
    modify (LBS.drop (fromIntegral n))
    return p

readLBS :: NetReader LBS.ByteString
readLBS = readULong >>= readBytes . fromIntegral

readString :: NetReader String
readString = fmap fromLBS readLBS

readBool :: NetReader Bool
readBool = readByte >>= return . (== 1)

