// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { AllEventTypes } from '@interfold/sdk/events'

export enum ProgramEventType {
  INPUT_PUBLISHED = 'InputPublished',
}

export type ProgramEvents = ProgramEventType | AllEventTypes

export interface InputPublishedEvent {
  e3Id: bigint
  data: string
  index: bigint
}

export interface RawInputPublishedEvent {
  eventName: string
  args: InputPublishedEvent
}
