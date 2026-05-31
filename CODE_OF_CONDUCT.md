# enShell Code of Conduct

## Our Pledge

We as contributors, maintainers, and community members of **enShell** pledge to make participation in this project a respectful, welcoming, and productive experience for everyone.

enShell exists to make computing more accessible by helping people use natural language to interact with terminals, operating systems, and developer tools. Because this project is designed especially for people who may not be deeply technical, we hold ourselves to a high standard of patience, clarity, safety, and respect.

We welcome people of all experience levels, backgrounds, identities, and perspectives.

## Our Standards

Examples of behavior that contributes to a positive community include:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Giving and receiving constructive feedback gracefully.
- Assuming good intent while also being accountable for impact.
- Helping beginners without condescension.
- Explaining technical concepts clearly and patiently.
- Prioritizing user safety, privacy, and trust.
- Respecting project maintainers’ time and decisions.
- Being transparent about risks, limitations, and tradeoffs.
- Focusing criticism on ideas, designs, code, and behavior rather than people.

Examples of unacceptable behavior include:

- Harassment, intimidation, threats, or personal attacks.
- Trolling, insulting or derogatory comments, or sustained disruption.
- Public or private harassment of any kind.
- Sexualized language or imagery where inappropriate.
- Unwelcome sexual attention or advances.
- Publishing others’ private information without explicit permission.
- Doxxing, stalking, or unwanted contact.
- Discriminatory jokes, slurs, or exclusionary behavior.
- Deliberately misleading users about safety, privacy, licensing, or model behavior.
- Encouraging unsafe system actions, destructive commands, or malicious use.
- Repeatedly ignoring maintainer guidance or community norms.
- Any other conduct that maintainers reasonably determine to be inappropriate in a professional open-source community.

## Technical Safety Expectations

Because enShell interacts with terminals and operating-system capabilities, contributors have additional responsibilities.

Contributors should:

- Treat user safety as a core project value.
- Avoid normalizing dangerous commands or unsafe defaults.
- Avoid suggesting destructive actions without clear warnings and safeguards.
- Respect the project principle that the LLM must not directly execute commands.
- Preserve the separation between model-generated plans and trusted Rust execution logic.
- Be careful when discussing `sudo`, privilege escalation, package installation, file deletion, shell scripts, remote execution, secrets, tokens, SSH keys, environment variables, and system configuration.
- Report potential security issues responsibly.
- Avoid posting exploit details publicly before maintainers have had a reasonable opportunity to assess and respond.

Contributors should not:

- Submit features that bypass the safety broker without clear review.
- Encourage silent execution of risky or destructive actions.
- Introduce hidden telemetry, data collection, or model-context capture.
- Add dependencies or model integrations without appropriate licensing review.
- Misrepresent third-party licensing, model weights, or external runtime requirements.
- Use enShell to facilitate malware, credential theft, unauthorized access, persistence, evasion, or other harmful activity.

## Accessibility and Beginner-Friendliness

enShell is intended to help people who may not know terminal commands. Community members should keep that audience in mind.

We encourage:

- Plain-English explanations.
- Beginner-friendly documentation.
- Clear examples.
- Gentle correction.
- Avoiding unnecessary jargon.
- Explaining acronyms on first use.
- Making room for questions that may seem basic to experienced developers.

We discourage:

- Gatekeeping.
- “RTFM” responses.
- Mocking people for not knowing commands.
- Designing only for expert users.
- Treating usability and documentation as secondary concerns.

## Scope

This Code of Conduct applies within all enShell project spaces, including but not limited to:

- GitHub repositories.
- Issues and pull requests.
- Discussions.
- Project chat rooms or forums.
- Community meetings.
- Documentation.
- Social media interactions when representing the project.
- Conferences, demos, workshops, or other events associated with enShell.

This Code of Conduct also applies when an individual is officially representing the project in public spaces.

## Reporting

If you experience or witness unacceptable behavior, please report it to the project maintainers.

The project intentionally does not publish a personal email address at this stage.
Reports can be made privately through GitHub:

- Contact a **MostViableProduct** organization maintainer directly through GitHub, or
- Open a private report via this repository's **Security** tab
  (**"Report a vulnerability"**), which routes privately to the maintainers.

A dedicated, separate reporting address may be added as the project's governance
matures.

Reports should include, when possible:

- A description of what happened.
- Where and when it happened.
- Relevant links, screenshots, or context.
- Names or handles of people involved.
- Whether the situation is ongoing.
- Any safety concerns that require urgent attention.

Maintainers will respect confidentiality as much as possible. Information will only be shared with those who need it to review, respond to, or resolve the situation.

## Enforcement Responsibilities

Project maintainers are responsible for clarifying and enforcing standards of acceptable behavior.

Maintainers may remove, edit, or reject comments, commits, issues, pull requests, documentation, or other contributions that are not aligned with this Code of Conduct.

Maintainers may also temporarily or permanently ban contributors or participants for behavior that they determine to be inappropriate, harmful, threatening, or disruptive.

## Enforcement Guidelines

Maintainers may take any action they deem appropriate and proportionate, including but not limited to:

### 1. Correction

For minor or unintentional issues, maintainers may provide private or public feedback and ask the participant to correct their behavior.

Possible outcome:

- Clarification of expectations.
- Edited comment or documentation.
- Apology or correction.

### 2. Warning

For repeated or more serious behavior, maintainers may issue a formal warning.

Possible outcome:

- Written warning.
- Clear expectations for future participation.
- Temporary moderation of comments or contributions.

### 3. Temporary Restriction

For serious or repeated violations, maintainers may temporarily restrict participation.

Possible outcome:

- Temporary ban from discussions.
- Temporary inability to open issues or pull requests.
- Removal from project communication spaces.

### 4. Permanent Ban

For severe violations, harassment, threats, malicious activity, or repeated disregard for community standards, maintainers may permanently remove the participant from the project community.

Possible outcome:

- Permanent ban from project spaces.
- Blocking on GitHub or other platforms.
- Removal from maintainer or contributor roles.

## Security-Related Reports

If the issue involves a security vulnerability, unsafe command execution, privilege escalation, secret exposure, malicious dependency, prompt injection exploit, or harmful agent behavior, please follow the project’s security reporting process instead of posting publicly.

Follow the process in [`SECURITY.md`](SECURITY.md): use **GitHub private
vulnerability reporting** via this repository's **Security** tab
(**"Report a vulnerability"**), which routes privately to the maintainers. Do not
open a public issue for security matters.

Security reports should not be used to harass contributors or bypass normal community moderation. Likewise, Code of Conduct reports should not be used to suppress legitimate security research or good-faith vulnerability disclosure.

## Good-Faith Participation

We recognize that disagreements happen in technical communities. Good-faith disagreement, design critique, security review, and architectural debate are welcome.

The following are acceptable when done respectfully:

- Criticizing code.
- Challenging technical assumptions.
- Raising safety concerns.
- Questioning licensing decisions.
- Debating architecture.
- Rejecting a pull request with a clear explanation.
- Asking for more evidence before accepting a claim.

The following are not acceptable:

- Personal attacks.
- Harassment.
- Bad-faith arguments.
- Repeated derailment.
- Dismissive or hostile responses to beginners.
- Retaliation against people who report concerns.

## Maintainer Conduct

Maintainers are expected to model the standards of this Code of Conduct.

Maintainers should:

- Respond respectfully.
- Avoid abusing authority.
- Apply rules consistently.
- Disclose conflicts of interest where relevant.
- Be transparent about project decisions when possible.
- Treat reports seriously.
- Protect reporters from retaliation.
- Prioritize user safety and community trust.

Maintainers who violate this Code of Conduct may be removed from maintainer roles by the project owner or governance body.

## Attribution

This Code of Conduct is inspired by widely used open-source community standards, including the Contributor Covenant, while adding project-specific expectations for safety, privacy, accessibility, and responsible AI-assisted system tooling.

## License

This Code of Conduct is provided as part of the enShell project documentation.

Unless otherwise stated, enShell project documentation is licensed under the same license as the project source code: Apache License 2.0.

## Version

Initial version: 0.1

This document may evolve as the enShell community, governance model, and security processes mature.
