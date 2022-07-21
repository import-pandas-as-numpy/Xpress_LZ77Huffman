# Xpress_LZ77Huffman
Microsoft Xpress : LZ77+Huffman Decompression Algorithm : Python3 implementation.

# Context
When attempting to read Windows 1.X prefetch files, windows uses a compression algorithm to encode the data.
This python script the implementation of the Xpress decompression algorithm used to encode those prefetch files.

The decompression algorithm is implemented into the "decompress_prefetch" function. Feel free to use it to decompress any other data using this compression method.

## Concrete use case
A prefetch volatility3 plugin using this algorithm is available here : TODO : put the link when the plugin is finished.

# References 
[Pseudo code algorithm] https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/%5bMS-XCA%5d.pdf [Section 2.2]
