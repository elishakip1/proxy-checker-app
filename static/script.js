let polling = false;

$("#proxy-form").submit(function(e) {
    e.preventDefault();
    let formData = new FormData(this);
    $("#status").text("Submitting...");
    $("#proxy-list").empty();
    $("#input-area").hide();

    $.ajax({
        url: "/submit",
        type: "POST",
        data: formData,
        processData: false,
        contentType: false,
        success: function(data) {
            $("#status").text(data.message);
            polling = true;
            pollResults();
        }
    });
});

function pollResults() {
    if (!polling) return;

    $.get("/results", function(data) {
        let displayed = $("#proxy-list li").length;
        let newResults = data.results.slice(displayed);

        newResults.forEach(proxy => {
            $("#proxy-list").append(`<li class='list-group-item'>${proxy}</li>`);
        });

        if (polling) setTimeout(pollResults, 2000);
    });
}
