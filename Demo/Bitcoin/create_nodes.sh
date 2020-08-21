rm -rf ~/.bitcoin/regtest
bitcoind -regtest -daemon
bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)
export ADVERSARY=$(bitcoin-cli -regtest getnewaddress)
export HONEST=$(bitcoin-cli -regtest getnewaddress)
bitcoin-cli -regtest sendtoaddress $ADVERSARY 10.00
bitcoin-cli -regtest sendtoaddress $HONEST 10.00
