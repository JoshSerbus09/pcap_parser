
def pcap_parse file
	file_lines = File.readlines(file)
	file_line_count = 0
	attributes = Hash.new
	ssids = Hash.new
	channels = Hash.new
	ssid_count = 0
	unique_ssid_count = 0


	file_lines.each { |row| 
		curr_row = row.split(",")
		file_line_count += 1

		curr_row.each { |item|

			# Record all of the unique SSIDS, slicing the string to remove [Packet yadda yadda]
			if item.include? 'SSID='
				if ssids[item] == nil
					if item.include? '['
						ssids[item] = item.slice(3..(item.index('[') - 1))
					else
						ssids[item] = item
					end		
					unique_ssid_count += 1	
				end
				ssid_count += 1
			end

		}
		attributes["ssids"] = ssids
	}

	puts "=============================================="
	puts "SSIDS found:"
	puts "=============================================="
	attributes["ssids"].each { |key, value|
		puts "#{value}"		
	}
	puts "=============================================="

	puts "Lines in CSV: " + file_line_count.to_s
	puts "SSIDS found: " + ssid_count.to_s
	puts "Unique SSIDS found: " + unique_ssid_count.to_s
end	

pcap_parse(File.open('pcap_CSV'))
