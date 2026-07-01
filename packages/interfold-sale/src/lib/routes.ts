// SPDX-License-Identifier: LGPL-3.0-only

import { ROUTES } from '../constants'
import type { RouteName } from '../types'

export function routeFromPath(pathname = window.location.pathname): RouteName {
  return pathname === '/admin' ? 'admin' : 'auction'
}

export function routePath(route: RouteName): string {
  return ROUTES.find((item) => item.route === route)?.path ?? '/auction'
}
