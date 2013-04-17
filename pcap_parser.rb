
def pcap_parse file
	file_lines = File.readlines(file)
	file_line_count = 0
	attributes = Hash.new
	ssids = Hash.new
	channels = Hash.new
	unique_channels_count = 0
	ssid_count = 0
	unique_ssid_count = 0


	file_lines.each { |row| 
		curr_row = row.split(",")
		file_line_count += 1

		curr_row.each { |item|

			# Record all of the unique SSIDS, slicing the string to remove [Packet yadda yadda]
			if item.include? 'SSID='
				if item.include? '['
					ssids[item] = item.slice(3..(item.index('[') - 1))
				else
					ssids[item] = item
				end		
				unique_ssid_count += 1	
			end

			# Record all the unique channels. Most likely all going to be 802.11
			if item.include? '802.11'
				channels[item] = item
				unique_channels_count += 1
			end		
		}
		attributes["ssids"] = ssids
		attributes["channels"] = channels
	}

	puts "=============================================="
	puts "SSIDS found:"
	puts "=============================================="
	attributes["ssids"].each { |key, value|
		puts "\t#{value}"		
	}
	puts "=============================================="
	puts "Channels found:"
	puts "=============================================="
		attributes["channels"].each { |key, value| 
			puts "\t#{value}"
		}
	puts "=============================================="

	puts "Lines in CSV: " + file_line_count.to_s
	puts "Unique SSIDS found: " + unique_ssid_count.to_s
	puts "Unique channels found: " + unique_channels_count.to_s
end	

pcap_parse(File.open('pcap_CSV'))
