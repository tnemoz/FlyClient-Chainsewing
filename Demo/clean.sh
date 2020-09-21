pkill bitcoind
rm -rf ~/.bitcoin/regtest
bitcoind -daemon -regtest
