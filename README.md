# Xpress_LZ77Huffman
Microsoft Xpress : LZ77+Huffman Decompression Algorithm : Python3 implementation.

# Context
When attempting to read Windows 1.X prefetch files, windows uses a compression algorithm to encode the data.
This python script the implementation of the Xpress decompression algorithm used to encode those prefetch files.

The decompression algorithm is implemented into the "decompress_prefetch" function. Feel free to use it to decompress any other data using this compression method.

## Use case
The prefetch volatility3 plugin is using this algorithm: https://www.forensicxlab.com/posts/prefetch/


# References
- Pseudo code algorithm : https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/%5bMS-XCA%5d.pdf [Section 2.2]
- Prefetch : https://forensicswiki.xyz/wiki/index.php?title=Windows_Prefetch_File_Format#File_header
- Blog : 
