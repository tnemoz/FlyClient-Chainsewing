CURDIR=$(pwd)
if [ -n "$ZSH_VERSION" ]; then
    cd $(dirname ${(%):-%N})
elif [ -n "$BASH_VERSION" ]; then
    cd $(dirname ${BASH_SOURCE[0]})
else
   echo "Please run the script using bash or zsh."
   exit 2
fi
mkdir -p miner
geth --datadir miner account new --password miner
geth --datadir miner init genesis.json
geth --identity miner --http --http.port 8000 --http.corsdomain "*" --datadir miner --port 30303 --nodiscover --http.api "eth,net,web3,personal,miner,admin" --networkid 1900 --nat "any"
cd $CURDIR
