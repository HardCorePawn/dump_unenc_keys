# dump_unenc_keys
Dumps private keys from unencrypted wallet.dat files using the "0201010420" private key marker

Searches through a given file looking for the "0201010420" byte marker, then extracts the next 32 bytes. Converts the hex to both Compressed and Uncompressed WIFs and dumps to STDOUT.

This script can NOT be used with wallet.dat's that have been encrypted.

Tested with Python 3 only.

Usage: python3 dump_unenc_keys.py unencrypted_wallet.dat
