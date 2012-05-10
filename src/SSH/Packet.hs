module SSH.Packet where

import Control.Monad.IO.Class
import Control.Monad.Trans.Writer
import Data.Binary (encode)
import Data.Bits ((.&.))
import Data.Digest.Pure.SHA
import Data.Word
import qualified Data.ByteString.Lazy as LBS

import SSH.Util


type Packet a = Writer LBS.ByteString a

byte :: Word8 -> Packet ()
byte = tell . encode

long :: Word32 -> Packet ()
long = tell . encode

integer :: Integer -> Packet ()
integer = tell . mpint

byteString :: LBS.ByteString -> Packet ()
byteString = tell . netLBS

string :: String -> Packet ()
string = byteString . toLBS

raw :: LBS.ByteString -> Packet ()
raw = tell

rawString :: String -> Packet ()
rawString = tell . toLBS

packetLength :: Packet () -> Int
packetLength = fromIntegral . LBS.length . doPacket

doPacket :: Packet a -> LBS.ByteString
doPacket = execWriter

netString :: String -> LBS.ByteString
netString = netLBS . toLBS

netLBS :: LBS.ByteString -> LBS.ByteString
netLBS bs = encode (fromIntegral (LBS.length bs) :: Word32) `LBS.append` bs

io :: MonadIO m => IO a -> m a
io = liftIO

unmpint :: LBS.ByteString -> Integer
unmpint = fromOctets (256 :: Integer) . LBS.unpack

mpint :: Integer -> LBS.ByteString
mpint i = netLBS (if LBS.head enc .&. 128 > 0
                      then 0 `LBS.cons` enc
                      else enc)
  where
    enc = LBS.pack (i2osp 0 i)

-- warning: don't try to send this; it's an infinite bytestring.
-- take whatever length the key needs.
makeKey :: Integer -> LBS.ByteString -> Char -> LBS.ByteString
makeKey s h c = makeKey' initial
  where
    initial = bytestringDigest . sha1 . LBS.concat $
        [ mpint s
        , h
        , LBS.singleton . fromIntegral . fromEnum $ c
        , h
        ]

    makeKey' acc = LBS.concat
        [ acc
        , makeKey' (bytestringDigest . sha1 . LBS.concat $ [mpint s, h, acc])
        ]

