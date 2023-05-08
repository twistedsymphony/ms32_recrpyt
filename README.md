# ms32_recrpyt
Allows decrypting and re-encryping of Jaleco MegaSystem 32 game data

The Jaleco Mega System 32 arcade hardware uses a cascading XOR encryption and address scrambling algorithm on the Background and Text data. This is facilitated on the cartridge through a custom protection chip. There are 4 known protection chips used across all games on the system.

This script's algorithms are based on the excellent decryption algorithms in MAME. It allows for decryping, encrypting, or both in a single command. The purpose being that a game can be re-encrypted for a different cartridge other than the one it originally came on.

# USAGE EXAMPLE

#reincrypt tetris plus background data for the SS92047-01 protection chip  
> python ms32_recrypt.py tetrisp\mr95024-03.10 new\mb95008-09.10 --gfx=bg --ic_in=SS92046-01 --ic_out=SS92047-01

#reincrypt tetris plus text data for the SS92047-01 protection chip  
> python ms32_recrypt.py tetrisp\mb93166_ver1.0-30.30 new\mb93166_ver1.0-30 --gfx=tx --ic_in=SS92046-01 --ic_out=SS92047-01

you can decrypt only or encrypt only by excluding the --ic_out and --ic_in parameters respectively
