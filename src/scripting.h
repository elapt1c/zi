/*
    Zorp scripting subsystem
*/
#ifndef SCRIPTING_H
#define SCRIPTING_H
#include "proto-banner1.h"
struct Zorp;

extern const struct ProtocolParserStream banner_scripting;

/**
 * Load the Lua scripting library and run the initialization
 * stage of all the specified scripts
 */
void scripting_init(struct Zorp *zorp);

/**
 * Create the "Zorp" object within the scripting subsystem
 */
void scripting_zorp_init(struct Zorp *zorp);

#endif

