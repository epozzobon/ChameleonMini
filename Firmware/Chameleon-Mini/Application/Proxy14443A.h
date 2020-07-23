/*
 * Proxy14443A.h
 *
 *  Created on: 20.05.2019
 *      Author: enrico
 */

#ifndef PROXY14443A_H_
#define PROXY14443A_H_

#include "Application.h"
#include "ISO14443-3A.h"

void Proxy14443AAppInit(void);

uint16_t Proxy14443AAppProcess(uint8_t* Buffer, uint16_t BitCount);

void Proxy14443AGetUid(ConfigurationUidType Uid);
void Proxy14443ASetUid(ConfigurationUidType Uid);
void Proxy14443AAppTask(void);
void Proxy14443AAppReset(void);
void Proxy14443ATick(void);

#endif /* PROXY14443A_H_ */
