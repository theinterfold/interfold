// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'

interface SpinnerProps {
  size?: number
}

const Spinner: React.FC<SpinnerProps> = ({ size = 18 }) => <span className='spin' style={{ width: size, height: size }} aria-hidden />

export default Spinner
