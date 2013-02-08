function deleteAccount() {
  if (confirm("All of your saved data will be lost. Continue?")) {
    $('#form_delete').submit();
  }
}