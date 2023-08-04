current_dir=$(pwd)
cd $(dirname $0)

python genmap.py
cd $current_dir