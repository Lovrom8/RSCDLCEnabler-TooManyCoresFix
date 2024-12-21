#pragma once

#include <iostream>
#include <fstream>

class DualLogger : public std::streambuf {
public:
    DualLogger(std::streambuf* consoleBuf, std::ostream& fileStream);

protected:
    int overflow(int c) override;
    int sync() override;

private:
    std::streambuf* consoleBuf;
    std::ostream& fileStream;
};

void InitializeLogging();