#pragma once

#include <iostream>
#include <fstream>


#include <iostream>
#include <fstream>
#include <streambuf>

class cDualLogger : public std::streambuf {
public:
	cDualLogger(std::streambuf* consoleBuf, std::ostream& fileStream);

	static void InitializeLogging();

protected:
	int overflow(int c) override;
	int sync() override;

private:
	std::streambuf* consoleBuf;
	std::ostream& fileStream;

	static cDualLogger* instance;
};
