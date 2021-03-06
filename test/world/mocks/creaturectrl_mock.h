/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Simon Sandström
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef COMMON_WORLD_MOCKS_CREATURECTRL_MOCK_H_
#define COMMON_WORLD_MOCKS_CREATURECTRL_MOCK_H_

#include "gmock/gmock.h"

#include "creaturectrl.h"
#include "creature.h"
#include "position.h"
#include "item.h"

class MockCreatureCtrl : public CreatureCtrl
{
 public:
  MOCK_METHOD2(onCreatureSpawn, void(const Creature& creature, const Position& position));
  MOCK_METHOD3(onCreatureDespawn, void(const Creature& creature, const Position& position, uint8_t stackPos));
  MOCK_METHOD5(onCreatureMove, void(const Creature& creature,
                                    const Position& oldPosition, uint8_t oldStackPos,
                                    const Position& newPosition, uint8_t newStackPos));
  MOCK_METHOD3(onCreatureTurn, void(const Creature& creature, const Position& position, uint8_t stackPos));
  MOCK_METHOD3(onCreatureSay, void(const Creature& creature, const Position& position, const std::string& message));
  MOCK_METHOD2(onItemRemoved, void(const Position& position, uint8_t stackPos));
  MOCK_METHOD2(onItemAdded, void (const Item& item, const Position& position));
  MOCK_METHOD1(onTileUpdate, void(const Position& position));
};

#endif  // COMMON_WORLD_MOCKS_CREATURECTRL_MOCK_H_
