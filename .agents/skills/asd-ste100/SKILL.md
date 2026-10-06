---
name: asd-ste100
description:
  Write, rewrite, and review technical prose with ASD-STE100 Issue 9 principles. Use for
  documentation, doc pages, READMEs, requirements, procedures, safety text, help text, release
  notes, PR prose, user-facing error messages, and reviews of such text. Short code comments need
  only the style rule in agent/RULES.md. Do not use it to rewrite protected code, identifiers,
  commands, quoted text, legal text, or exact interface literals.
---

# ASD-STE100 technical writing

Apply this skill when you add, change, or review documentation or other longer natural-language
technical content. For short code comments, the style rule in `agent/RULES.md` §Working rules is
enough: current behavior and its reason, in short, active sentences.

Preserve technical meaning before simplifying language. Do not change a fact, condition, sequence,
requirement strength, limit, unit, identifier, or safety classification to satisfy a writing rule.

## Workflow

1. Classify the text as a procedure, description, safety instruction, requirement, or protected
   literal.
2. Preserve code, identifiers, commands, paths, URLs, equations, API names, UI labels, log output,
   quotations, required legal text, and interface-stable message literals exactly. Apply the writing
   rules to new messages and to messages that are safe to change.
3. Read [references/rules.md](references/rules.md). Apply the sections relevant to the text.
4. Use one consistent project-approved term for each concept.
5. Prefer short active sentences, direct verbs, explicit subjects, and parallel lists.
6. For procedures, use imperative verbs and one action per step.
7. Check the final text against the preservation rules and final audit in the reference.

## Compliance boundary

Use `STE-verified` only when you checked the official Issue 9 dictionary, project terminology, and
all applicable writing rules.

Use `STE-aligned` when the official dictionary or complete project terminology is unavailable. Never
claim official compliance, certification, approval, or endorsement from this skill alone.

When missing information could change the technical meaning, use:

`[NEEDS TECHNICAL INPUT: state the missing fact or decision]`

## Default output

- For an ordinary coding or documentation task, apply the rules silently. Do not add a compliance
  label unless the user asks for one.
- For a rewrite request, return only the revised text unless the user asks for analysis.
- For a writing review or compliance check, use the response templates in the reference.

The official current source is the
[ASD Simplified Technical English Maintenance Group](https://www.asd-ste100.org/). Issue 9 was
published on 2025-01-15.
