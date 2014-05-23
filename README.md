# Heartbleed exploit implementation

## Installing

### Installing GHC (Haskell)

Install the [Haskell Platform](https://www.haskell.org/platform).

open a terminal and updated cabal packages and install a new version:
~~~
cabal update
cabal install cabal-install
~~~

Also make sure to add the new cabal install binary location to your path
(~/.cabal/bin on Mac OS).

### Directly running
For quick tests, the code can be run directly with the following command:
~~~
runhaskell Main.hs
~~~
Note however, that this runs in the interpreter and is much slower than the
compiled binary. This should however not be a big Problem in this case.

### Build the exploit
~~~
git clone https://github.com/Codas/heartbleed
cd heartbleed
cabal sandbox init && cabal install && cabal build
~~~

### Run the exploit binary
~~~
./dist/build/heartbleed/heartbleed --help
~~~
