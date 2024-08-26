# BuildKite

The configuration files for BuildKite builds are located in `.buildkite/*.yml`\
BuildKite build are often self-hosted, this means that you may gain excessive privileges to the kubernetes cluster that runs the runners, or to the hosting cloud environment. 

In order to run an OS command in a workflow that builds pull requests - simply add a `command` instruction to the step.

```yaml
steps:
  - label: "Example Test"
    command: echo "Hello!"
```
