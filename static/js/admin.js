// Graph

function deleteAppointment(id) {
    if (confirm("Are you sure you want to delete this appointment?")) {
      $.ajax({
        url: "/delete_appointment/" + id,
        type: "POST",
        success: function(result) {
          location.reload();
        }
      });
    }
  }

