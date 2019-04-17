/*******************************************************************************
 * Copyright (C) 2004-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corporation. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corporation. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef __CHANNEL_GENERATOR_H__
#define __CHANNEL_GENERATOR_H__

#include <set>

#define ILLEGAL_CHANNEL 0
#define MAX_CHANNEL_DEFAULT 1000

/*
	The purpose of this class is to manage allocated LMS-side channel side and generate new ones
*/

class ChannelGenerator
{
public:

   ChannelGenerator() :
  _maxChannel(MAX_CHANNEL_DEFAULT), 
  _nextFreeChannel(1) {}
  
  
   ChannelGenerator(unsigned int maxChannel) :
  _maxChannel(maxChannel), 
  _nextFreeChannel(1) {}
	
  ~ChannelGenerator() {}

	//returns ILLEGAL_CHANNEL if failed
	unsigned int GenerateChannel();

	// returns false if did not find
	bool FreeChannel(unsigned int channel);

	// reverts to initial state
	void Reset();

private:
	unsigned int _maxChannel;
	std::set<unsigned int> _takenChannels;
	unsigned int _nextFreeChannel;
};

#endif

