module SSH.Util where

import Data.Word (Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS


toLBS :: String -> LBS.ByteString
toLBS = LBS.pack . map (fromIntegral . fromEnum)

fromLBS :: LBS.ByteString -> String
fromLBS = map (toEnum . fromIntegral) . LBS.unpack

strictLBS :: LBS.ByteString -> BS.ByteString
strictLBS = BS.concat . LBS.toChunks

powersOf :: Num a => a -> [a]
powersOf n = 1 : (map (*n) (powersOf n))

toBase :: (Integral a, Num b) => a -> a -> [b]
toBase x =
   map fromIntegral .
   reverse .
   map (flip mod x) .
   takeWhile (/=0) .
   iterate (flip div x)

toOctets :: (Integral a, Integral b) => a -> b -> [Word8]
toOctets n x = (toBase n . fromIntegral) x

fromOctets :: (Integral a, Integral b) => a -> [Word8] -> b
fromOctets n x =
   fromIntegral $
   sum $
   zipWith (*) (powersOf n) (reverse (map fromIntegral x))

i2osp :: Integral a => Int -> a -> [Word8]
i2osp l y =
   pad ++ z
      where
         pad = replicate (l - unPaddedLen) (0x00::Word8)
	 z = toOctets (256 :: Integer) y
	 unPaddedLen = length z