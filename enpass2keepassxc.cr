require "base64"
require "http/params"
require "json"
require "uri"
require "xml"

module Enpass
  class Export
    include JSON::Serializable

    property folders : Array(Folder)
    property items : Array(Item)

    class Folder
      include JSON::Serializable

      property uuid : String
      property parent_uuid : String
      property title : String
      property icon : String
      property updated_at : Int64
    end

    class Item
      include JSON::Serializable

      property uuid : String
      property title : String
      property auto_submit : Int32
      property category : String
      property favorite : Int32
      property folders : Array(String)?
      property fields : Array(Item::Field)?
      property note : String
      property subtitle : String
      property template_type : String
      property updated_at : Int64

      class Field
        include JSON::Serializable

        property label : String
        property type : String
        property history : Array(Field::History)?
        property order : Int32
        property sensitive : Int32
        property uid : Int32
        property updated_at : Int64
        property value : String
        property value_updated_at : Int64

        class History
          include JSON::Serializable

          property updated_at : Int64
          property value : String
        end
      end
    end
  end
end

def uuid_str_to_b64(uuid : String)
  raise "not a uuid" unless uuid.size == 36

  bytes = uuid.gsub("-", "").scan(/../).map(&.[](0).to_u8(16))
  io = IO::Memory.new(bytes.size)
  bytes.each { |b| io.write_byte b }
  Base64.encode(io).strip
end

def unix_to_iso8601(time)
  Time::Format::ISO_8601_DATE_TIME.format(Time.unix(time))
end

def icon_for_category(category)
  {
    "license"    => "17",
    "note"       => "44",
    "creditcard" => "66",
    "finance"    => "66",
  }.fetch(category, "0")
end

def build_entry(xml, item)
  # creation time seems to be just the oldest updated_at value of any field
  created_at = item.updated_at
  if item.fields
    created_at = item.fields.not_nil!.map(&.updated_at).min
  end

  xml.element("Entry") do
    xml.element("UUID") { xml.text(uuid_str_to_b64(item.uuid)) }

    xml.element("IconID") { xml.text(icon_for_category(item.category)) }
    %w[ForegroundColor BackgroundColor OverrideURL Tags].each do |t|
      xml.element(t)
    end

    xml.element("Times") do
      xml.element("LastModificationTime") { xml.text(unix_to_iso8601(item.updated_at)) }
      xml.element("CreationTime") { xml.text(unix_to_iso8601(created_at)) }
      xml.element("LastAccessTime") { xml.text(unix_to_iso8601(item.updated_at)) }
      xml.element("ExpiryTime") { xml.text(unix_to_iso8601(Int32::MAX)) }
      xml.element("Expires") { xml.text("False") }
      xml.element("UsageCount") { xml.text("0") }
      xml.element("LocationChanged") { xml.text(unix_to_iso8601(item.updated_at)) }
    end

    xml.element("String") do
      xml.element("Key") { xml.text("Title") }
      xml.element("Value") { xml.text(item.title) }
    end

    xml.element("String") do
      xml.element("Key") { xml.text("Notes") }
      xml.element("Value") { xml.text(item.note) unless item.note.empty? }
    end

    username : String? = nil
    email : String? = nil

    custom_attributes_count = {} of String => Int32

    if item.fields
      item.fields.not_nil!.each do |field|
        key = field.label
        value_args = {} of String => String
        value_args["ProtectInMemory"] = "True" unless field.sensitive.zero?

        case field.type
        when "username"
          username = field.value unless field.value.empty?
          next # handled below
        when "email"
          email = field.value unless field.value.empty?
          next # handled below
        when "password"
          key = "Password"
        when "url"
          key = "URL"
        when "totp"
          next # handled below
        else
          # don't care if we don't have a value for non-mandatory fields
          next if field.value.empty?
        end

        custom_attributes_count[key] ||= 0
        custom_attributes_count[key] += 1
        if custom_attributes_count[key] > 1
          key = "#{key} (#{custom_attributes_count[key]})"
        end

        xml.element("String") do
          xml.element("Key") { xml.text(key) }
          xml.element("Value", value_args) { xml.text(field.value) unless field.value.empty? }
        end
      end

      # set the UserName to the email if the username is not set
      if !email.nil? && !email.not_nil!.empty?
        key = "UserName"

        if !username.nil? && !username.not_nil!.empty?
          xml.element("String") do
            xml.element("Key") { xml.text("UserName") }
            xml.element("Value") { xml.text(username) }
          end

          key = "E-Mail"
        end

        xml.element("String") do
          xml.element("Key") { xml.text(key) }
          xml.element("Value") { xml.text(email) }
        end
      else
        xml.element("String") do
          xml.element("Key") { xml.text("UserName") }
          xml.element("Value") { xml.text(username) if !username.nil? && !username.not_nil!.empty? }
        end
      end

      totp_fields = item.fields.not_nil!.select { |f| f.type == "totp" && !f.value.empty? }
      unless totp_fields.size.zero?
        # get the most recent TOTP value
        totp_value = totp_fields.sort_by(&.value_updated_at).last.value
        # normalise it
        totp_value = totp_value.gsub(" ", "").upcase

        totp_params = HTTP::Params.encode({"secret" => totp_value,
                                           "period" => "30",
                                           "digits" => "6",
                                           "issuer" => item.title})
        totp_uri = URI.new(
          scheme: "otpauth",
          host: "totp",
          path: URI.encode_path([item.title, "someone"].join(":")), # here's hoping keepassxc doesn't care about the username in here
          query: totp_params
        ).to_s

        xml.element("String") do
          xml.element("Key") { xml.text("otp") }
          xml.element("Value", {"ProtectInMemory" => "True"}) { xml.text(totp_uri) }
        end
      end
    end

    xml.element("AutoType") do
      xml.element("Enabled") { xml.text("True") }
      xml.element("DataTransferObfuscation") { xml.text("0") }
      xml.element("DefaultSequence")
    end

    xml.element("History")
  end
end

def convert_enpass_export(enpass)
  entries_by_group = enpass.items.group_by(&.folders)

  root_uuid = "5ca246df-de73-47fe-b4a9-28ae68817f78"
  watch_uuid = "d275de30-d63b-4a07-a3ca-1be78047ba14"

  XML.build(indent: "  ") do |xml|
    xml.element("KeePassFile") do
      xml.element("Meta") do
        xml.element("Generator") { xml.text("Enpass2KeepassXC") }
        xml.element("MemoryProtection") do
          xml.element("ProtectTitle") { xml.text("False") }
          xml.element("ProtectUserName") { xml.text("False") }
          xml.element("ProtectPassword") { xml.text("True") }
          xml.element("ProtectURL") { xml.text("False") }
          xml.element("ProtectNotes") { xml.text("False") }
        end
      end

      xml.element("Root") do
        xml.element("Group") do
          xml.element("UUID") { xml.text(uuid_str_to_b64(root_uuid)) }
          xml.element("Name") { xml.text("Root") }
          xml.element("Notes")
          xml.element("IconID") { xml.text("48") }
          xml.element("IsExpanded") { xml.text("True") }

          entries_by_group[nil].each do |item|
            build_entry(xml, item)
          end

          entries_by_group.each do |group, items|
            next unless group
            folder_uuid = group.first

            folder_metadata = enpass.folders.find { |f| f.uuid == folder_uuid }

            next unless folder_metadata
            folder_metadata = folder_metadata.not_nil!

            folder_uuid = watch_uuid if folder_uuid == "watch-folder-uuid"

            xml.element("Group") do
              xml.element("UUID") { xml.text(uuid_str_to_b64(folder_uuid)) }
              xml.element("Name") { xml.text(folder_metadata.title) }
              xml.element("Notes")
              xml.element("IconID") { xml.text("48") }
              xml.element("IsExpanded") { xml.text("True") }

              items.each do |item|
                build_entry(xml, item)
              end
            end
          end
        end
      end
    end
  end
end

def main(argv)
  abort "usage: enpass2keepassxc JSON_EXPORT" if argv.size != 1

  enpassfile = argv.shift
  enpass_export = Enpass::Export.from_json(File.read(enpassfile))

  document = convert_enpass_export(enpass_export)

  puts document
end

main ARGV.dup
