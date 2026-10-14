#pragma once
// Cases of secure_frontend_fetch_tests defined outside fetch_test.cpp.
namespace fetch_cases {
// fetch_file_test.cpp (Task 21)
void dl03_truncated_body_rejected();
void dl03_oversize_body_rejected_mid_stream();
void dl03_redirect_to_http_rejected();
void dl03_redirect_off_allowlist_rejected();
void dl03_redirect_limit();
void redirect_query_only_in_config_line();
void dl03_private_address_rejected();
void dl03_mixed_public_private_answer_rejected();
void dl03_range_ignored_restarts_from_zero();
void dl03_content_range_mismatch_rejected();
void dl03_content_encoding_gzip_fails_digest();
void dl03_stalled_source_times_out();
void time_budget_exceeded_is_resumable();
void tls_untrusted_moves_to_next_source();
void digest_mismatch_after_resume_refetches_once();
void free_space_rechecked_while_writing();
void ipv6_only_hop_is_address_not_allowed();
void range_ignored_twice_is_range_mismatch_then_restarts();
void proxy_hop_skips_address_policy();
#if defined(SECURE_FRONTEND_TEST_HOOKS)
void test_cacert_reaches_argv_in_hook_builds();
#endif
}  // namespace fetch_cases
