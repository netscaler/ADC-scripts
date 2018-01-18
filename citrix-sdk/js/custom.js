$(document).ready(function(){
	
	var expedli = $('.toctree-l1.current');
	var expedlis = $('.toctree-l1.current').siblings(".toctree-l1");
	expedli.show();
	expedlis.show();
	if ( expedli.css('display') != 'none' ){
		expedli.parent().prev().children().children().removeClass('fa-angle-down').addClass('fa-angle-up');
		
		//clispan.removeClass('fa-plus-square-o').addClass('fa-minus-square-o');		
	}
$(document).ready(function(){
	
	var expedli = $('.toctree-l1.current');
	var expedlis = $('.toctree-l1.current').siblings(".toctree-l1");
	expedli.show();
	expedlis.show();
	if ( expedli.css('display') != 'none' ){
		expedli.parent().prev().children().children().removeClass('fa-angle-down').addClass('fa-angle-up');
		
		//clispan.removeClass('fa-plus-square-o').addClass('fa-minus-square-o');		
	}
	$("li").click(function(){
		var span = $(this).children().eq(0);
		var i = span.children('i').eq(0);
		if (i.hasClass("faexp")){
		//eq(0).hasClass
			if (i.hasClass('fa-angle-down')){
				var nextul = i.parent().parent().next();
				var nextlis = nextul.children(".toctree-l1 ").show(200);
				i.removeClass('fa-angle-down').addClass('fa-angle-up');	
			}
			else{
				var nextul = i.parent().parent().next();
				var nextlis = nextul.children(".toctree-l1 ").hide(200);
				i.removeClass('fa-angle-up').addClass('fa-angle-down');
			}
		}
	})
	/*
	$(".faexp").click(function(){
		if ($(this).hasClass('fa-angle-down')){
		var nextul = $(this).parent().parent().next();
		var nextlis = nextul.children(".toctree-l1 ").show(200);
		$(this).removeClass('fa-angle-down').addClass('fa-angle-up');
			
		}
		else{
					var nextul = $(this).parent().parent().next();
		var nextlis = nextul.children(".toctree-l1 ").hide(200);
		$(this).removeClass('fa-angle-up').addClass('fa-angle-down');
			
		}
	
	});
	*/
	$(".expli").click(function(){
		var ul = $(this).siblings("ul");
		//if ( ul.css('display') == 'none' ){
		if ($('.expli').children('.fa').hasClass('fa-plus-square-o')){		
			//$('.expli').children('.fa').removeClass('fa-plus-square-o').addClass('fa-minus-square-o');
			ul.show(300);
		}
		else{	
			//$('.expli').children('.fa').removeClass('fa-minus-square-o').addClass('fa-plus-square-o');
			ul.hide(300);
		}
	})
	$(".expul >i.fa").click(function(){
		var lis = $(this).parent().parent().siblings(".toctree-l1 ");
		if ( $(this).hasClass('fa-plus-square-o')){
			//$(this).removeClass('fa-plus-square-o').addClass('fa-minus-square-o');
			lis.show(300);
		}
		else{
			var lic = $(this).parent().parent().siblings(".current");
			var lispan = $(this).parent().parent().siblings(".current >span");				
			//$(this).removeClass('fa-minus-square-o').addClass('fa-plus-square-o');
			lis.hide(300);
		}
	})
	if ($('li.toctree-l1.current').length) {
	var nav = $('li.toctree-l1.current').offset().top;
	$(".wy-nav-side").scrollTop(nav-80);
	}
});
	
	$(".expli").click(function(){
		var ul = $(this).siblings("ul");
		//if ( ul.css('display') == 'none' ){
		if ($('.expli').children('.fa').hasClass('fa-plus-square-o')){		
			//$('.expli').children('.fa').removeClass('fa-plus-square-o').addClass('fa-minus-square-o');
			ul.show(300);
		}
		else{	
			//$('.expli').children('.fa').removeClass('fa-minus-square-o').addClass('fa-plus-square-o');
			ul.hide(300);
		}
	})
	$(".expul >i.fa").click(function(){
		var lis = $(this).parent().parent().siblings(".toctree-l1 ");
		if ( $(this).hasClass('fa-plus-square-o')){
			//$(this).removeClass('fa-plus-square-o').addClass('fa-minus-square-o');
			lis.show(300);
		}
		else{
			var lic = $(this).parent().parent().siblings(".current");
			var lispan = $(this).parent().parent().siblings(".current >span");				
			//$(this).removeClass('fa-minus-square-o').addClass('fa-plus-square-o');
			lis.hide(300);
		}
	})
	if ($('li.toctree-l1.current').length) {
	var nav = $('li.toctree-l1.current').offset().top;
	$(".wy-nav-side").scrollTop(nav-80);
	}
});