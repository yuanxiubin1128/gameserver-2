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

#include "creature.h"

const CreatureId Creature::INVALID_ID = 0;
CreatureId Creature::nextCreatureId_ = 0x4713;

Creature::Creature(const std::string& name)
  : creatureId_(Creature::getFreeCreatureId()),
    name_(name),
    direction_(SOUTH),
    maxHealth_(100),
    health_(100),
    speed_(900),
    lightColor_(0),
    lightLevel_(0),
    stepSpeed_(220)
{
  outfit_.type = 128;
  outfit_.head = 20;
  outfit_.body = 30;
  outfit_.legs = 40;
  outfit_.feet = 50;
}

bool Creature::operator==(const Creature& other) const
{
  return creatureId_ == other.creatureId_;
}

bool Creature::operator!=(const Creature& other) const
{
  return !(*this == other);
}
