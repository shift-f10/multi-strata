#pragma once
// Cases of secure_frontend_acquire_tests defined outside acquire_test.cpp.
namespace acquire_cases {
// acquire_store_test.cpp (Task 16)
void concurrent_pull_same_manifest_second_is_models_busy();
void part_file_create_append_resume_truncate();
void rename_within_never_replaces();
void rename_fallback_never_replaces();
void remove_tree_removes_links_without_following();
void hash_into_rejects_hard_links_and_counts_bytes();
void store_environment_seams_report_space_and_fs_kind();
void overlong_joined_paths_fail_closed_without_throwing();
#if defined(_WIN32)
// acquire_store_windows_test.cpp (Task 17)
void store_primitives_windows();
void store_adopts_only_private_files_windows();
#endif
}  // namespace acquire_cases
