// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// NavMenu.tsx
import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { List } from '@phosphor-icons/react'
//Icons
import { CalendarCheck, CheckFat, Notebook } from '@phosphor-icons/react'

const NAV_MENU_OPTIONS = [
  {
    name: 'Current Poll',
    icon: <CalendarCheck />,
    path: '/current',
  },
  {
    name: 'All Polls',
    icon: <CheckFat />,
    path: '/all',
  },
  {
    name: 'About',
    icon: <Notebook />,
    path: '/about',
  },
]

const NavMenu: React.FC = () => {
  const navigate = useNavigate()
  const menuRef = useRef<HTMLDivElement>(null)
  const [isOpen, setIsOpen] = useState<boolean>(false)
  const buttonRef = useRef<HTMLButtonElement>(null)

  const handleClickOutside = React.useCallback(
    (event: MouseEvent) => {
      if (
        isOpen &&
        menuRef.current &&
        !menuRef.current.contains(event.target as Node) &&
        !buttonRef.current?.contains(event.target as Node)
      ) {
        setIsOpen(false)
      }
    },
    [isOpen],
  )

  const toggleMenu = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation()
    setIsOpen(!isOpen)
  }

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen, handleClickOutside])

  const handleNavigation = (path: string) => {
    navigate(path)
    return setIsOpen(!isOpen)
  }

  return (
    <div className='relative md:hidden'>
      <button
        ref={buttonRef}
        onClick={toggleMenu}
        className='flex items-center justify-between space-x-1 rounded-[12px] bg-white/70 px-2 py-2 duration-300 ease-in-out hover:bg-white'
      >
        <List size={24} />
      </button>

      <div
        ref={menuRef}
        className={`absolute right-0 mt-4 w-40 transform rounded-[12px] bg-white/70 p-4 
          ${isOpen ? 'scale-100' : 'scale-0'}`}
      >
        <div className='space-y-2'>
          {NAV_MENU_OPTIONS.map(({ name, path, icon }) => (
            <div key={name} className='flex cursor-pointer space-x-2 rounded p-1 hover:bg-gray-100' onClick={() => handleNavigation(path)}>
              {icon}
              <p className='block rounded-md text-sm font-semibold '>{name}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default NavMenu
