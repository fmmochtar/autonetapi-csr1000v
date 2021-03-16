from nescient.elasticclient import get_netflow_resampled

normal_start_time = "2021-03-14T14:11:53"
normal_end_time = "2021-03-14T14:17:02"
dos_start_time = "2021-03-14T14:19:53"
dos_end_time = "2021-03-14T14:24:05"

normal_data_object_array = get_netflow_resampled(start_time=normal_start_time, end_time=normal_end_time)
dos_data_object_array = get_netflow_resampled(start_time=dos_start_time, end_time=dos_end_time)

# prepare elastic data

data_to_be_used = normal_data_object_array # switch this variable for other case


