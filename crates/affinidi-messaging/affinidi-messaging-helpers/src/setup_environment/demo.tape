# To create the demo tape gif
# Run from the affinidi-messaging top level directory
# vhs affinidi-messaging-sdk/examples/setup_environment/demo.tape
# Where should we write the GIF?
Output setup_environment_demo.gif

# Set up a 2400x1200 terminal with 46px font.
Set FontSize 18
Set Width 3000
Set Height 1200

# Type a command in the terminal.
Type "cargo run --example setup_environment"

# Pause for dramatic effect...
Sleep 1s

# Run the command by pressing enter.
Enter

# Admire the output for a bit.
Sleep 5s

# Configure Local Mediator
Type "y"
Sleep 2s

# Create Mediator DID
Type "y"
Sleep 2s

# Create Administration DID
Type "y"
Sleep 2s

# Create JWT Token Secrets
Type "y"
Sleep 2s

# Save Mediator Configuration
Type "y"
Sleep 2s

# Create SSL Certificates
Type "y"
Sleep 2s

Sleep 10s