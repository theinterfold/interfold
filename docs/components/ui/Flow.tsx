// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { CSSProperties, Fragment, ReactNode } from 'react'
import { Icon, IconName } from './Icon'
import classes from './ui.module.css'

export type FlowStepData = {
  label: string
  sub?: ReactNode
  icon?: IconName
}

/**
 * Horizontal pipeline with animated connectors. It changes to a vertical layout on narrow screens.
 * Use it for a sequence of four or five steps at most.
 */
export function Flow({ steps, label }: { steps: FlowStepData[]; label?: string }) {
  return (
    <ol className={classes.flow} aria-label={label}>
      {steps.map((step, i) => (
        <Fragment key={step.label}>
          {i > 0 ? <li aria-hidden='true' className={classes.flowLink} style={{ '--delay': `${i * 300}ms` } as CSSProperties} /> : null}
          <li className={classes.flowStep}>
            {step.icon ? (
              <span className={classes.flowStepIcon}>
                <Icon name={step.icon} size={18} />
              </span>
            ) : null}
            <span className={classes.flowStepLabel}>{step.label}</span>
            {step.sub ? <span className={classes.flowStepSub}>{step.sub}</span> : null}
          </li>
        </Fragment>
      ))}
    </ol>
  )
}

export type LayerData = {
  name: string
  note?: string
  items: string[]
}

/** Stacked layers, for example an architecture from the application down to the chain. */
export function Layers({ layers }: { layers: LayerData[] }) {
  return (
    <div className={classes.layers}>
      {layers.map((layer) => (
        <div key={layer.name} className={classes.layer}>
          <div className={classes.layerTitle}>
            <span className={classes.layerName}>{layer.name}</span>
            {layer.note ? <span className={classes.layerNote}>{layer.note}</span> : null}
          </div>
          <div className={classes.layerItems}>
            {layer.items.map((item) => (
              <span key={item} className={classes.layerItem}>
                {item}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
