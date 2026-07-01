// SPDX-License-Identifier: LGPL-3.0-only
import { connect } from "./cli";
import { planPath, writeJson } from "./files";
import { buildSalePlan, printPlan } from "./plan";
import type { SalePlan } from "./types";
import { loadConfig } from "./values";

export async function actionPlan(): Promise<SalePlan> {
  const { ethers } = await connect();
  const config = loadConfig();
  const plan = await buildSalePlan(ethers, config);
  const file = planPath(config);
  writeJson(file, plan);
  printPlan(plan, file);
  return plan;
}

