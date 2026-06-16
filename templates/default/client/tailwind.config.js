// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

const config = {
  content: ['./src/**/*.{js,jsx,ts,tsx,mdx}'],
  variant: {
    extend: {
      borderColor: ['disabled'],
      backgroundColor: ['disabled'],
      textColor: ['disabled'],
      boxShadow: ['disabled'],
      cursor: ['disabled'],
    },
  },
  theme: {
    extend: {
      fontFamily: {
        jakarta: ['Plus Jakarta Sans', 'sans-serif'],
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
      },
      colors: {
        slate: {
          200: '#E3E9F5',
        },
        interfold: {
          50: '#eff9ff',
          100: '#def2ff',
          200: '#b6e8ff',
          300: '#75d8ff',
          400: '#2cc4ff',
          500: '#60c2ff',
          600: '#0ea5e9',
          700: '#0284c7',
          800: '#0369a1',
          900: '#0c4a6e',
          950: '#082f49',
        },
      },
      letterSpacing: {
        custom: '0.03em',
      },
      boxShadow: {
        button: '0 2px 0 0 #5F9715, 0 8px 16px rgba(0,0,0,0.1)',
        'button-outlined': '0 2px 0 0 #A6E05A, 0 8px 16px rgba(0,0,0,0.1)',
        danger: '0 2px 0 0 #EF4444, 0 8px 16px rgba(0,0,0,0.1)',
      },
    },
  },
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  plugins: [require('@tailwindcss/typography')],
}
export default config
