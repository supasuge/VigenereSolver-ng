#!/bin/bash

if [ ! -d "data" ]; then
    mkdir data
fi

wget http://practicalcryptography.com/media/cryptanalysis/files/english_monograms.txt -O data/english_monograms.txt
echo "monograms downloaded..."

wget http://practicalcryptography.com/media/cryptanalysis/files/english_words.txt.zip -O data/english_words.txt.zip
echo "words downloaded..."

unzip data/english_words.txt.zip
echo "words unzipped..."
wget http://practicalcryptography.com/media/cryptanalysis/files/english_bigrams_1.txt -O data/english_bigrams_1.txt
echo 'bigrams downloaded... [1]'

wget http://practicalcryptography.com/media/cryptanalysis/files/english_trigrams.txt.zip -O data/english_trigrams.txt.zip
unzip data/english_trigrams.txt.zip
echo 'trigrams downloaded... [1]'

wget http://practicalcryptography.com/media/cryptanalysis/files/english_quadgrams.txt.zip -O data/english_quadgrams.txt.zip
unzip data/english_quadgrams.txt.zip
echo 'quadgrams downloaded... [1]'

wget http://practicalcryptography.com/media/cryptanalysis/files/english_pentagrams.txt.zip -O data/english_pentagrams.txt.zip
unzip data/english_pentagrams.txt.zip
echo 'pentagrams downloaded... [1]'

echo "done"