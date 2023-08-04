current_dir=$(pwd)
cd $(dirname $0)

python docgen.py
cd $current_dir