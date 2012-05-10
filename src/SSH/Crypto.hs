module SSH.Crypto where

import Control.Monad (replicateM)
import Control.Monad.Trans.State
import Data.ASN1.BER (decodeASN1Stream)
import Data.ASN1.Stream
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Data.List (isPrefixOf)
import qualified Codec.Binary.Base64.String as B64
import qualified Codec.Crypto.RSA as RSA
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Data.ByteString.Lazy as LBS
import qualified OpenSSL.DSA as DSA

import SSH.Packet
import SSH.NetReader
import SSH.Util

data Cipher =
    Cipher
        { cType :: CipherType
        , cMode :: CipherMode
        , cBlockSize :: Int
        , cKeySize :: Int
        }

data CipherType = AES
data CipherMode = CBC

data HMAC =
    HMAC
        { hDigestSize :: Int
        , hFunction :: LBS.ByteString -> LBS.ByteString
        }

data PublicKey
    = RSAPublicKey
        { rpubE :: Integer
        , rpubN :: Integer
        }
    | DSAPublicKey
        { dpubP :: Integer
        , dpubQ :: Integer
        , dpubG :: Integer
        , dpubY :: Integer
        }
    deriving (Eq, Show)

data KeyPair
    = RSAKeyPair
        { rprivPub :: PublicKey
        , rprivD :: Integer
        }
    | DSAKeyPair
        { dprivPub :: PublicKey
        , dprivX :: Integer
        }
    deriving (Eq, Show)


rsaKeyPairFromFile :: FilePath -> IO KeyPair
rsaKeyPairFromFile fn = do
    x <- readFile fn
    let asn1
            = B64.decode
            . concat
            . filter (not . ("--" `isPrefixOf`))
            . lines
            $ x

    case decodeASN1Stream (toLBS asn1) of
        Right (Start Sequence:ss)
            | all isIntVal (fst $ getConstructedEnd 0 ss) ->
            let (is, _) = getConstructedEnd 0 ss
            in return $ RSAKeyPair
                { rprivPub = RSAPublicKey
                    { rpubE = intValAt 2 is
                    , rpubN = intValAt 1 is
                    }
                , rprivD = intValAt 3 is
                }
        Right u -> error ("unknown ASN1 decoding result: " ++ show u)
        Left e -> error ("ASN1 decoding of private key failed: " ++ show e)
  where
    isIntVal (IntVal _) = True
    isIntVal _ = False

    intValAt i is =
        case is !! i of
            IntVal n -> n
            x -> error ("not an IntVal: " ++ show x)

generator :: Integer
generator = 2

safePrime :: Integer
safePrime = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007

toBlocks :: (Integral a) => a -> LBS.ByteString -> [LBS.ByteString]
toBlocks _ m | m == LBS.empty = []
toBlocks bs m = b : rest
  where
    b = LBS.take (fromIntegral bs) m
    rest = toBlocks bs (LBS.drop (fromIntegral bs) m)

fromBlocks :: [LBS.ByteString] -> LBS.ByteString
fromBlocks = LBS.concat

modexp :: Integer -> Integer -> Integer -> Integer
modexp = modexp' 1
  where
    modexp' y _ 0 _ = y
    modexp' y z e n
        | e `mod` 2 == 1 = modexp' (y * z `mod` n) ((z ^ (2 :: Integer)) `mod` n) (e `div` 2) n
        | otherwise = modexp' y ((z ^ (2 :: Integer)) `mod` n) (e `div` 2) n

blob :: PublicKey -> LBS.ByteString
blob (RSAPublicKey e n) = doPacket $ do
    string "ssh-rsa"
    integer e
    integer n
blob (DSAPublicKey p q g y) = doPacket $ do
    string "ssh-dss"
    integer p
    integer q
    integer g
    integer y

blobToKey :: LBS.ByteString -> PublicKey
blobToKey s = flip evalState s $ do
    t <- readString

    case t of
        "ssh-rsa" -> do
            e <- readInteger
            n <- readInteger
            return $ RSAPublicKey e n
        "ssh-dss" -> do
            [p, q, g, y] <- replicateM 4 readInteger
            return $ DSAPublicKey p q g y
        u -> error $ "unknown public key format: " ++ u

sign :: KeyPair -> LBS.ByteString -> IO LBS.ByteString
sign (RSAKeyPair (RSAPublicKey _ n) d) m = return $ LBS.concat
    [ netString "ssh-rsa"
    , netLBS (RSA.rsassa_pkcs1_v1_5_sign RSA.ha_SHA1 (RSA.PrivateKey 256 n d 0 0 0 0 0) m)
    ]
sign (DSAKeyPair (DSAPublicKey p q g y) x) m = do
    (r, s) <- DSA.signDigestedDataWithDSA (DSA.tupleToDSAKeyPair (p, q, g, y, x)) digest
    return $ LBS.concat
        [ netString "ssh-dss"
        , netLBS $ LBS.concat
            [ LBS.pack $ i2osp 20 r
            , LBS.pack $ i2osp 20 s
            ]
        ]
  where
    digest = strictLBS . bytestringDigest . sha1 $ m
sign _ _ = error "sign: invalid key pair"
