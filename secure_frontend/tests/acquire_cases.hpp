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
// acquire_publish_test.cpp (Task 19)
void dl04_publish_uses_noreplace_and_never_overwrites();
void publish_falls_back_when_noreplace_unsupported();
#if defined(SECURE_FRONTEND_TEST_HOOKS)
void dl04_crash_between_publish_and_index_is_not_loaded();
#endif
void dl04_orphan_adopted_after_rehash_by_digest();
void replace_loaded_model_retires_old_version();
void layout_check_requires_pack_files_and_valid_tokenizer();
void staged_tree_must_be_exactly_the_manifest();
void install_decisions_follow_sequence_rules();
void publish_requires_staging_key_of_manifest();
void overlong_staging_tree_is_publish_failed();
void retire_removes_read_only_published_version();
void downgrade_adopts_retired_version_keeping_one_live();
void rm_refuses_held_version_and_removes_read_only_tree();
#if !defined(_WIN32)
void rm_reports_unreachable_version_as_failure();
#endif
#if defined(_WIN32)
void replace_loaded_model_retires_old_version_windows();
#endif
#if defined(_WIN32)
// acquire_store_windows_test.cpp (Task 17)
void store_primitives_windows();
void store_adopts_only_private_files_windows();
#endif
}  // namespace acquire_cases
