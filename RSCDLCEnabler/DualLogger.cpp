#include "DualLogger.h"

DualLogger::DualLogger(std::streambuf* consoleBuf, std::ostream& fileStream)
    : consoleBuf(consoleBuf), fileStream(fileStream) {}

int DualLogger::overflow(int c) {
    if (c != EOF) {
        consoleBuf->sputc(c);
        fileStream.put(c);
    }
    return c;
}

int DualLogger::sync() {
    consoleBuf->pubsync();
    fileStream.flush();
    return 0;
}

std::ofstream logFile;

void InitializeLogging() {
    logFile.open("log.txt", std::ios::out | std::ios::app);
    if (!logFile) {
        std::cerr << "Failed to open log file." << std::endl;
        return;
    }

    static DualLogger dualCoutBuf(std::cout.rdbuf(), logFile);
    static DualLogger dualCerrBuf(std::cerr.rdbuf(), logFile);

    std::cout.rdbuf(&dualCoutBuf);
    std::cerr.rdbuf(&dualCerrBuf);
}
