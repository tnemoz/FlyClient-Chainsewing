CURDIR=$(pwd)
if [ -n "$ZSH_VERSION" ]; then
    cd $(dirname ${(%):-%N})
elif [ -n "$BASH_VERSION" ]; then
    cd $(dirname ${BASH_SOURCE[0]})
else
   echo "Please run the script using bash or zsh."
   exit 2
fi
mkdir miner
geth --datadir miner account new
geth --datadir miner init genesis.json
cd $CURDIR
