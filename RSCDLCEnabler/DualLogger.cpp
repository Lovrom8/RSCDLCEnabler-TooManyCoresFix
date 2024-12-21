#include "DualLogger.h"

cDualLogger* cDualLogger::instance = nullptr;

cDualLogger::cDualLogger(std::streambuf* consoleBuf, std::ostream& fileStream)
	: consoleBuf(consoleBuf), fileStream(fileStream) {}

int cDualLogger::overflow(int c) {
	if (c != EOF) {
		if (consoleBuf) {
			consoleBuf->sputc(c);
		}
		fileStream.put(c);
	}
	return c;
}

int cDualLogger::sync() {
	if (consoleBuf) {
		consoleBuf->pubsync();
	}
	fileStream.flush();
	return 0;
}

void cDualLogger::InitializeLogging() {
    if (instance) {
        return;
    }

    static auto logFile = std::make_unique<std::ofstream>("log.txt", std::ios::out | std::ios::app);
    if (!logFile->is_open()) {
        std::cerr << "Failed to open log file." << std::endl;
        return;
    }

    instance = new cDualLogger(std::cout.rdbuf(), *logFile);

    std::cout.rdbuf(instance);
    std::cerr.rdbuf(instance);
}