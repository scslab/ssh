module SSH.Debug where

import Debug.Trace


debugging :: Bool
debugging = False

debug :: (Show a, Show b) => b -> a -> a
debug s v
    | debugging = trace (show s ++ ": " ++ show v) v
    | otherwise = v

dump :: (Monad m, Show a) => a -> m ()
dump x
    | debugging = trace (show x) (return ())
    | otherwise = return ()

