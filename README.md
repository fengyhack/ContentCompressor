# ContentCompressor
ZStd with zstandard or GZip with igzip



# ZStdCompress #

```c++
#include <string>
#include "Compressor.h"

using namespace std;
using namespace zio::compression;

int main(int argc, char** argc)
{
    string outfile = "<XXX>.zst";
    auto format = Format::GZip;
    Compressor cx(outfile, format, Mode::Write, true)
    byte[] data = new byte[size];
    cx.Put(data, size);
    cx.Close();
    if (cx.FileSize() > 0)
    {
        bool md5fx = true;
        string delim = "  ";
        auto hash = cx.GetHashStr(md5fx, delim));
        //todo with hash...
    }
    return 0;
}
```



## ZStdCompress ##

ZStd compression



## GZipCompress ##

GZip compression



## ZExtract ##

Decompress from `ZStd` to binary



## ZConv ##

Convert from `ZStd` to `GZip`



# BinComp #

Binary compare `bc <file1> <file2>`

