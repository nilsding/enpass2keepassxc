# enpass2keepassxc

A quick and dirty Crystal script to convert an Enpass JSON export to a KeePassXC
XML file, which can be then imported via `keepassxc-cli`.

## Features

This script can migrate the following:

- Folders to Groups
- TOTP fields
- Any additional non-empty fields
  - It even migrates duplicate field names!
- Sensitivity values of fields
- Adds icons for some entries
- Attempts to guess the created and updated at values of an entry

And it does not use CSV anywhere!

## Installation

You only need Crystal 1.12.2 or newer.

## Usage

First of all, export your existing Enpass database to JSON. This can be done via
_Menu_ > _File_ > _Export_ and selecting `.json` as the file format.

Then convert your exported Enpass database to XML by running this script:

```sh
crystal run enpass2keepassxc.cr -- ~/path/to/exported_passwords.json > ./imported_from_enpass.xml
```

Finally, create a new KeePass database using KeePassXC's CLI:

```
keepassxc-cli import ./imported_from_enpass.xml ~/Documents/MyPasswords.kdbx
```

You're done!

## Contributing

1. Fork it (<https://github.com/nilsding/enpass2keepassxc/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Jyrki Gadinger](https://github.com/nilsding) - creator and maintainer
